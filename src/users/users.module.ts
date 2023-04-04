import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { AuthService } from 'src/auth/auth.service';
import { JwtService } from '@nestjs/jwt';
import { CryptoService } from 'src/crypto/crypto.service';
import { BlacklistedToken } from './entities/token-blacklist.entity';
import { MailerService } from 'src/mailer/mailer.service';
import { PasswordResetToken } from './entities/password-reset-token.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User, BlacklistedToken, PasswordResetToken])],
  controllers: [UsersController],
  providers: [UsersService, AuthService, JwtService, CryptoService, MailerService],
  exports: [UsersService],
})
export class UsersModule {}
