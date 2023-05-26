import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { BlacklistedToken } from './entities/token-blacklist.entity';
import { PasswordResetToken } from './entities/password-reset-token.entity';
import { WINSTON_MODULE_PROVIDER, WinstonLogger, WinstonModule } from 'nest-winston';
import { MockBlacklistedTokenRepository, MockPasswordResetTokenRepository, MockUsersRepository } from 'src/mocks/repository.mock';
import { MockWinston } from 'src/mocks/winston.mock';

describe('UsersService', () => {
  let service: UsersService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [UsersService, MockUsersRepository, MockBlacklistedTokenRepository, MockPasswordResetTokenRepository, MockWinston],
    }).compile();

    service = module.get<UsersService>(UsersService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
