import { Test, TestingModule } from '@nestjs/testing';
import { PostsController } from './posts.controller';
import { PostsService } from './posts.service';
import { Casbin } from 'src/casbin/casbin';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MockBlacklistedTokenRepository, MockPasswordResetTokenRepository, MockPostsRepository, MockUsersRepository } from 'src/mocks/repository.mock';
import { MockWinston } from 'src/mocks/winston.mock';
import { UsersService } from 'src/users/users.service';

describe('PostsController', () => {
  let controller: PostsController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [PostsController],
      providers: [PostsService, PostsController, UsersService, Casbin, JwtService, ConfigService, MockPostsRepository, MockUsersRepository, MockBlacklistedTokenRepository, MockPasswordResetTokenRepository, MockWinston],
    }).compile();

    controller = module.get<PostsController>(PostsController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
