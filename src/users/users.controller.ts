import { Controller, Get, Post, Body, Version, ValidationPipe, Request, HttpStatus, UseGuards, Req, HttpException, UnauthorizedException, HttpCode, Put, Query, Delete, Param } from '@nestjs/common';
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
import { ApiAcceptedResponse, ApiBadRequestResponse, ApiBearerAuth, ApiConflictResponse, ApiCreatedResponse, ApiForbiddenResponse, ApiNotFoundResponse, ApiOkResponse, ApiOperation, ApiQuery, ApiTags, ApiUnauthorizedResponse } from '@nestjs/swagger';
import { BadRequestError, ConflictError, DefaultUnauthorizedError, ErrorResponse, ForbiddenError, InsufficientPermissionsError, NotFoundError, SetupMFAResponse, TokenPair, UnauthorizedError } from 'src/swagger/swagger.responses';
import { Casbin } from 'src/casbin/casbin';
import { RBACObject } from 'src/casbin/enum/object.enum';
import { RBACAction } from 'src/casbin/enum/action.enum';
import { InsufficientPermissionsException } from 'src/errors/insufficient-permissions.exception';

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService, private authService: AuthService, private cryptoService: CryptoService, private mailerService: MailerService, private casbin: Casbin) { }

  @ApiOperation({ summary: "Registers a user into the system.", description: "Inserts a user into the database if the username or email haven't already been taken." })
  @ApiCreatedResponse({ description: 'User has been successfully created', type: TokenPair })
  @ApiConflictResponse({ description: 'Username or email already exists', type: ConflictError })
  @Version('1')
  @Post('register')
  async create(@Body(new ValidationPipe()) createUserDto: CreateUserDto) {
    const createdUser = await this.usersService.create(createUserDto);

    return await this.authService.generateTokenPair(createdUser);
  }

  @ApiOperation({
    summary: "Returns an access token if the credentials are correct.",
    description: "Access token and refresh token are returned if the username and password are correct. The totp field must be provided if the user has 2FA enabled. If not, it can be completely left out."
  })
  @ApiOkResponse({ description: 'User successfully logged in', type: TokenPair })
  @ApiUnauthorizedResponse({ description: 'Username, password or totp code is incorrect', type: UnauthorizedError })
  @ApiForbiddenResponse({ description: 'The user has 2FA enabled, but the totp code was not provided', type: ForbiddenError })
  @Version('1')
  @Post('login')
  async login(@Body(new ValidationPipe()) loginUserDto: LoginUserDto) {
    return this.authService.login(loginUserDto.username, loginUserDto.password, loginUserDto.totp);
  }


  @ApiOperation({
    summary: "Login via a recovery code.",
    description: "Access token and refresh token are returned if the username, password and recovery code are correct. This endpoint can only be used if the user has 2FA enabled but has lost access to the TOTP secret."
  })
  @ApiOkResponse({ description: "User successfully logged in", type: TokenPair })
  @ApiUnauthorizedResponse({ description: 'Username, password or recovery code is incorrect', type: UnauthorizedError })
  @Version('1')
  @Post('login/recovery')
  async loginRecovery(@Body(new ValidationPipe()) loginUserRecoveryDto: LoginUserRecoveryDto) {
    const user = await this.authService.validateLoginCredentials(loginUserRecoveryDto.username, loginUserRecoveryDto.password);

    await this.usersService.loginUserRecovery(user, loginUserRecoveryDto.recoveryCode);

    return await this.authService.generateTokenPair(user);
  }

  @ApiOperation({ summary: "Generates a TOTP secret." })
  @ApiBearerAuth()
  @ApiOkResponse({ description: 'TOTP code generated successfully', type: SetupMFAResponse })
  @ApiUnauthorizedResponse({ description: 'The access token is invalid', type: DefaultUnauthorizedError })
  @Version('1')
  @UseGuards(JwtGuard)
  @Get('mfa')
  async setupMfa() {
    const secret = this.authService.generateMfaSecret();

    return { secret }
  }

  @ApiOperation({ summary: "Checks if provided totp code is correct and enables 2FA for the user." })
  @ApiBearerAuth()
  @ApiBadRequestResponse({ description: 'The totp code is incorrect', type: BadRequestError })
  @ApiUnauthorizedResponse({ description: 'The access token is invalid', type: DefaultUnauthorizedError })
  @Version('1')
  @UseGuards(JwtGuard)
  @Put('mfa/confirm')
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

  @ApiOperation({
    summary: "Returns a fresh token pair.",
    description: "Used only when the access token has expired. If a previously used refresh token is used again, the user's account will be locked for security reasons."
  })
  @ApiOkResponse({ description: "Tokens have been refreshed successfully", type: TokenPair })
  @ApiUnauthorizedResponse({ description: "The access token or refresh token is invalid", type: DefaultUnauthorizedError })
  @ApiBearerAuth()
  @Version('1')
  @HttpCode(HttpStatus.OK)
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


  @ApiOperation({ summary: "Sends a password reset email." })
  @ApiAcceptedResponse({ description: "Email has been sent" })
  @ApiNotFoundResponse({ description: "The provided email does not exist", type: NotFoundError })
  @Version('1')
  @HttpCode(HttpStatus.ACCEPTED)
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

  @ApiOperation({ summary: "Changes the user's password." })
  @ApiQuery({ name: "password reset token" })
  @ApiOkResponse({ description: "Password has been changed successfully" })
  @ApiBadRequestResponse({ description: 'The password reset token was not provided', type: BadRequestError })
  @Version('1')
  @HttpCode(HttpStatus.OK)
  @Put('password-reset')
  async resetUserPassword(@Body(new ValidationPipe()) passwordResetDto: PasswordResetDto, @Query() query) {
    const { token } = query;
    if (!token) {
      throw new HttpException('please provide a password reset token', HttpStatus.BAD_REQUEST);
    }

    await this.usersService.resetUserPasswordByResetToken(passwordResetDto.password, token);
  }


  @ApiOperation({ summary: "Deletes a user.", description: "User deletions are controlled with permissions. A normal user cannot delete another user, only admins can." })
  @ApiOkResponse({description: "User deleted successfully"})
  @ApiForbiddenResponse({ description: "Insufficient permissions", type: InsufficientPermissionsError })
  @ApiUnauthorizedResponse({ description: "The access token is invalid", type: DefaultUnauthorizedError })
  @Version('1')
  @UseGuards(JwtGuard)
  @Delete(':id')
  async deleteUser(@Param('id') id: number, @Request() req) {
    const user: User = req.user;

    const canDelete = await this.casbin.enforce(user.role.name, RBACObject.User, RBACAction.Delete);
    if (!canDelete) {
      throw new InsufficientPermissionsException()
    }

    await this.usersService.remove(id);
  }
}