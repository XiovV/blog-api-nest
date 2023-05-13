import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import * as argon2 from 'argon2';
import { BlacklistedToken } from './entities/token-blacklist.entity';
import { PasswordResetToken } from './entities/password-reset-token.entity';
import { Role } from './entities/role.entity';
import { Role as RoleEnum} from './enum/role.enum';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name)
  constructor(@InjectRepository(User) private usersRepository: Repository<User>, @InjectRepository(BlacklistedToken) private blacklistedTokenRepository: Repository<BlacklistedToken>, @InjectRepository(PasswordResetToken) private passwordResetTokenRepository: Repository<PasswordResetToken>) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    const user = new User();
    user.username = createUserDto.username;
    user.email = createUserDto.email;
    user.password = await argon2.hash(createUserDto.password);

    const defaultRole = new Role();
    defaultRole.id = RoleEnum.Normal;
    user.role = defaultRole;

    const existingUsername = await this.usersRepository.findOneBy({ username: createUserDto.username });
    if (existingUsername) {
      this.logger.error({username: createUserDto.username, email: createUserDto.email, error: 'username already exists'}, 'failed to create user')
      throw new HttpException('username already exists', HttpStatus.CONFLICT);
    }

    const existingEmail = await this.usersRepository.findOneBy({ email: createUserDto.email })
    if (existingEmail) {
      this.logger.error({username: createUserDto.username, email: createUserDto.email, error: 'email already exists'}, 'failed to create user')
      throw new HttpException('email already exists', HttpStatus.CONFLICT);
    }

    const result = await this.usersRepository.insert(user);
    this.logger.log({username: createUserDto.username, email: createUserDto.email}, 'user created successfully')

    user.id = result.identifiers[0].id;

    return user;
  }

  async loginUserRecovery(user: User, recoveryCode: string) {
    const isRecoveryCodeValid = user.recovery.includes(recoveryCode);

    if (!isRecoveryCodeValid) {
      throw new HttpException('recovery code is incorrect', HttpStatus.UNAUTHORIZED);
    }

    user.recovery = user.recovery.filter(code => code !== recoveryCode);

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
