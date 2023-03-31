import { Module } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { CryptoService } from 'src/crypto/crypto.service';
import { UsersModule } from 'src/users/users.module';
import { AuthService } from './auth.service';

@Module({
  imports: [UsersModule, PassportModule],
  providers: [AuthService, JwtService, CryptoService],
})
export class AuthModule {}
