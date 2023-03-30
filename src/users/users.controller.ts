import { Controller, Get, Post, Body, Patch, Param, Delete, Version, ValidationPipe, Request, HttpStatus, UseGuards, Req, HttpException, UnauthorizedException, HttpCode } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LocalAuthGuard } from 'src/auth/local-auth.guard';
import { AuthService } from 'src/auth/auth.service';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { User } from './entities/user.entity';
import { ConfirmMfaDto } from './dto/confirm-mfa.dto';
import { CryptoService } from 'src/crypto/crypto.service';
import { LoginUserMfaDto } from './dto/login-user-mfa.dto';

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
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user)
  }

  @Version('1')
  @Post('login/mfa')
  async loginMfa(@Body(new ValidationPipe()) loginUserMfaDto: LoginUserMfaDto) {
    const user = await this.authService.validateUser(loginUserMfaDto.username, loginUserMfaDto.password);
    
    const decryptedSecret = await this.cryptoService.decryptMfaSecret(user.mfaSecret);

    const isTOTPValid = this.authService.verifyTOTPCode(loginUserMfaDto.totp, decryptedSecret);

    if (!isTOTPValid) {
      throw new HttpException('the totp code is incorrect', HttpStatus.UNAUTHORIZED);
    }

    return await this.authService.generateTokenPair(user);
  }

  @Version('1')
  @UseGuards(JwtAuthGuard)
  @Get('mfa')
  async setupMfa() {
    const secret = this.authService.generateMfaSecret();

    return { secret }
  }

  @Version('1')
  @UseGuards(JwtAuthGuard)
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

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(+id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(+id);
  }
}
