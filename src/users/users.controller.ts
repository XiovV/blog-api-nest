import { Controller, Get, Post, Body, Patch, Param, Delete, Version, ValidationPipe, Request, HttpStatus, UseGuards, Req, HttpException, UnauthorizedException, HttpCode } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { AuthService } from 'src/auth/auth.service';
import { User } from './entities/user.entity';
import { ConfirmMfaDto } from './dto/confirm-mfa.dto';
import { CryptoService } from 'src/crypto/crypto.service';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtGuard } from 'src/auth/auth.guard';
import { LoginUserRecoveryDto } from './dto/login-user-recovery.dto';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService, private authService: AuthService, private cryptoService: CryptoService) { }

  @Version('1')
  @Post('register')
  async create(@Body(new ValidationPipe()) createUserDto: CreateUserDto) {
    const createdUser = await this.usersService.create(createUserDto);

    return await this.authService.generateTokenPair(createdUser);
  }

  @Version('1')
  @Post('login')
  async login(@Body(new ValidationPipe()) loginUserDto: LoginUserDto) {
    return this.authService.login(loginUserDto.username, loginUserDto.password, loginUserDto.totp);
  }

  @Version('1')
  @Post('login/recovery')
  async loginRecovery(@Body(new ValidationPipe()) loginUserRecoveryDto: LoginUserRecoveryDto) {
    const user = await this.authService.validateLoginCredentials(loginUserRecoveryDto.username, loginUserRecoveryDto.password);

    return await this.usersService.loginUserRecovery(user, loginUserRecoveryDto.recoveryCode);
  }

  @Version('1')
  @UseGuards(JwtGuard)
  @Get('mfa')
  async setupMfa() {
    const secret = this.authService.generateMfaSecret();

    return { secret }
  }

  @Version('1')
  @UseGuards(JwtGuard)
  @Post('mfa/confirm')
  async confirmMfa(@Body(new ValidationPipe()) confirmMfaDto: ConfirmMfaDto, @Request() req) {
    if (!this.authService.verifyTOTPCode(confirmMfaDto.totp, confirmMfaDto.secret)) {
      throw new HttpException('the provided totp is invalid', HttpStatus.BAD_REQUEST);
    }

    const recoveryCodes = this.authService.generateRecoveryCodes();
    const encryptedSecret = await this.cryptoService.encryptMfaSecret(confirmMfaDto.secret);

    const user: User = req.user;

    await this.usersService.saveMfaDetails(user, encryptedSecret, recoveryCodes);
    return recoveryCodes;
  } 

}
