import { HttpException, HttpStatus, Inject, Injectable, LoggerService } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import * as argon2 from 'argon2';
import { BlacklistedToken } from './entities/token-blacklist.entity';
import { PasswordResetToken } from './entities/password-reset-token.entity';
import { Role } from './entities/role.entity';
import { Role as RoleEnum } from './enum/role.enum';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { Logger } from 'winston'

@Injectable()
export class UsersService {
  private readonly logger: Logger

  constructor(@InjectRepository(User) private usersRepository: Repository<User>, @InjectRepository(BlacklistedToken) private blacklistedTokenRepository: Repository<BlacklistedToken>, @InjectRepository(PasswordResetToken) private passwordResetTokenRepository: Repository<PasswordResetToken>, @Inject(WINSTON_MODULE_PROVIDER) private readonly winston: Logger) {
    this.logger = this.winston.child({ context: UsersService.name })
  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    const childLogger = this.logger.child({ username: createUserDto.username, email: createUserDto.email })
    childLogger.info('attempting to create a new user')

    const user = new User();
    user.username = createUserDto.username;
    user.email = createUserDto.email;
    user.password = await argon2.hash(createUserDto.password);

    const defaultRole = new Role();
    defaultRole.id = RoleEnum.Normal;
    user.role = defaultRole;

    const existingUsername = await this.usersRepository.findOneBy({ username: createUserDto.username });
    if (existingUsername) {
      childLogger.error('failed to create user', { error: 'username already exists' })
      throw new HttpException('username already exists', HttpStatus.CONFLICT);
    }

    const existingEmail = await this.usersRepository.findOneBy({ email: createUserDto.email })
    if (existingEmail) {
      childLogger.error('failed to create user', { error: 'email already exists' })
      throw new HttpException('email already exists', HttpStatus.CONFLICT);
    }

    const result = await this.usersRepository.insert(user);
    childLogger.info('user created successfully')

    user.id = result.identifiers[0].id;

    return user;
  }

  async loginUserRecovery(user: User, recoveryCode: string) {
    const childLogger = this.logger.child({ username: user.username })
    childLogger.info('attempting to log a user in via a recovery code')

    const isRecoveryCodeValid = user.recovery.includes(recoveryCode);
    if (!isRecoveryCodeValid) {
      childLogger.warn('failed to log user in via a recovery code', { error: 'recovery code is incorrect' })
      throw new HttpException('recovery code is incorrect', HttpStatus.UNAUTHORIZED);
    }

    user.recovery = user.recovery.filter(code => code !== recoveryCode);

    childLogger.info('user logged in successful')

    await this.usersRepository.save(user);
  }

  async insertBlacklistedToken(user: User, refreshToken: string) {
    const token = new BlacklistedToken();
    token.token = refreshToken;
    token.user = user;

    await this.blacklistedTokenRepository.save(token)
  }

  async isTokenBlacklisted(refreshToken: string): Promise<boolean> {
    const foundToken = await this.blacklistedTokenRepository.findOneBy({ token: refreshToken })
    if (!foundToken) {
      return false;
    }

    return true;
  }

  generatePasswordResetToken(): string {
    return Math.random().toString(32).substring(2, 14);
  }

  async setActiveStatus(user: User, isActive: boolean) {
    user.isActive = isActive;

    await this.usersRepository.save(user);
  }

  private async updateUserPassword(user: User, password: string) {
    console.log(user)

    user.password = await argon2.hash(password);

    await this.usersRepository.save(user);
  }

  async resetUserPasswordByResetToken(password: string, token: string) {
    const resetToken = await this.passwordResetTokenRepository.findOneBy({})

    const currentTime = Date.now()
    if (resetToken.expiry < currentTime) {
      throw new HttpException('this token has expired, please request a new one', HttpStatus.GONE);
    }

    const user = await resetToken.user;
    await this.updateUserPassword(user, password)
  }

  async insertPasswordResetToken(user: User, passwordResetToken: string) {
    const resetToken = new PasswordResetToken();
    resetToken.token = passwordResetToken;
    resetToken.user = user;

    const currentTime = new Date();
    currentTime.setMinutes(currentTime.getMinutes() + 20)

    resetToken.expiry = currentTime.getTime();

    await this.passwordResetTokenRepository.save(resetToken);
  }

  async findOneByUsername(username: string): Promise<User | undefined> {
    return await this.usersRepository.findOneBy({ username })
  }

  async findOneByEmail(email: string): Promise<User | undefined> {
    return await this.usersRepository.findOneBy({ email })
  }

  async saveMfaDetails(user: User, secret: Buffer, recoveryCodes: string[]) {
    user.recovery = recoveryCodes;
    user.mfaSecret = ("\\x" + secret.toString("hex")) as any;

    this.usersRepository.save(user);
  }

  findAll() {
    return `This action returns all users`;
  }

  async findOneById(id: number): Promise<User | undefined> {
    const res: User[] = await this.usersRepository.find({ where: { id }, relations: { role: true } })
    return res[0]
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  async remove(id: number) {
    await this.usersRepository.delete(id)
  }

}
