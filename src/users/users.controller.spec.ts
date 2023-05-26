import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { userStub } from './stubs/user.stub';
import { PostsService } from 'src/posts/posts.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Post } from 'src/posts/entities/post.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from 'src/auth/auth.service';
import { CryptoService } from 'src/crypto/crypto.service';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { MailerService } from 'src/mailer/mailer.service';
import { Casbin } from 'src/casbin/casbin';
import { MockPostsRepository, MockUsersRepository } from 'src/mocks/repository.mock';
import { MockWinston } from 'src/mocks/winston.mock';

jest.mock('./users.service')
jest.mock('../auth/auth.service')

describe('UsersController', () => {
  let controller: UsersController;
  let service: UsersService;
  let postsService: PostsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [UsersService, PostsService, JwtService, ConfigService, AuthService, CryptoService, MailerService, Casbin, MockPostsRepository, MockUsersRepository, MockWinston],
    }).compile();

    controller = module.get<UsersController>(UsersController);
    service = module.get<UsersService>(UsersService);
    postsService = module.get<PostsService>(PostsService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('createUser', () => {
    describe('when createUser is called', () => {
      let createUserDto: CreateUserDto

      beforeEach(async () => {
        createUserDto = {
          email: userStub().email,
          username: userStub().email,
          password: userStub().password,
        }

       await controller.create(createUserDto)
      })

      test('then it should call usersService', () => {
        expect(service.create).toHaveBeenCalledWith(createUserDto)
      })
    })
  })
});
