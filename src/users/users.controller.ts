import { Controller, Get, Post, Body, Version, ValidationPipe, Request, HttpStatus, UseGuards, Req, HttpException, UnauthorizedException, HttpCode, Put, Query } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { AuthService } from 'src/auth/auth.service';
import { User } from './entities/user.entity';
import { ConfirmMfaDto } from './dto/confirm-mfa.dto';
import { CryptoService } from 'src/crypto/crypto.service';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtGuard } from 'src/auth/jwt.guard';
import { LoginUserRecoveryDto } from './dto/login-user-recovery.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { MailerService } from 'src/mailer/mailer.service';
import { PasswordResetEmailDto } from './dto/password-reset-email.dto';
import { PasswordResetDto } from './dto/password-reset.dto';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService, private authService: AuthService, private cryptoService: CryptoService, private mailerService: MailerService) { }

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

    await this.usersService.loginUserRecovery(user, loginUserRecoveryDto.recoveryCode);

    return await this.authService.generateTokenPair(user);
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

  @Version('1')
  @UseGuards(JwtGuard)
  @Post('token/refresh')
  async refreshToken(@Body(new ValidationPipe()) refreshTokenDto: RefreshTokenDto, @Request() req) {
    const user: User = req.user;

    try {
      await this.authService.validateRefreshToken(refreshTokenDto.refreshToken, user.id);
    } catch (error) {
      throw error;
    }

    const isTokenBlacklisted = await this.usersService.isTokenBlacklisted(refreshTokenDto.refreshToken)

    if (isTokenBlacklisted) {
      this.usersService.setActiveStatus(user, false);

      throw new UnauthorizedException();
    }

    await this.usersService.insertBlacklistedToken(user, refreshTokenDto.refreshToken);

    return await this.authService.generateTokenPair(user);
  }

  @Version('1')
  @Post('password-reset')
  async sendPasswordResetMail(@Body(new ValidationPipe()) passwordResetEmailDto: PasswordResetEmailDto) {
    const user = await this.usersService.findOneByEmail(passwordResetEmailDto.email)
    if (!user) {
      throw new HttpException('a user with this email does not exist', HttpStatus.NOT_FOUND);
    }

    const passwordResetToken = this.usersService.generatePasswordResetToken();

    await this.usersService.insertPasswordResetToken(user, passwordResetToken)

    this.mailerService.sendPasswordResetMail(user.email, user.username, passwordResetToken);
  }

  @Version('1')
  @Put('password-reset')
  async resetUserPassword(@Body(new ValidationPipe()) passwordResetDto: PasswordResetDto, @Query() query) {
    const { token } = query;
    if (!token) {
      throw new HttpException('please provide a password reset token', HttpStatus.BAD_REQUEST);
    }

    await this.usersService.resetUserPasswordByResetToken(passwordResetDto.password, token);
  }
}
