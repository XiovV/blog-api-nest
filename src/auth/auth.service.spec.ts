import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { CryptoService } from 'src/crypto/crypto.service';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { BlacklistedToken } from 'src/users/entities/token-blacklist.entity';
import { PasswordResetToken } from 'src/users/entities/password-reset-token.entity';
import { MockBlacklistedTokenRepository, MockPasswordResetTokenRepository, MockUsersRepository } from 'src/mocks/repository.mock';
import { MockWinston } from 'src/mocks/winston.mock';

describe('AuthService', () => {
  let service: AuthService;
  let usersService: UsersService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuthService, UsersService, JwtService, ConfigService, CryptoService, MockUsersRepository, MockBlacklistedTokenRepository, MockPasswordResetTokenRepository, MockWinston],
    }).compile();

    service = module.get<AuthService>(AuthService);
    usersService = module.get<UsersService>(UsersService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
