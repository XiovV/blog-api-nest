import { Module } from '@nestjs/common';
import { PostsService } from './posts.service';
import { PostsController } from './posts.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Post } from './entities/post.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from 'src/users/users.service';
import { User } from 'src/users/entities/user.entity';
import { BlacklistedToken } from 'src/users/entities/token-blacklist.entity';
import { PasswordResetToken } from 'src/users/entities/password-reset-token.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Post, User, BlacklistedToken, PasswordResetToken])],
  controllers: [PostsController],
  providers: [PostsService, ConfigService, UsersService, JwtService],
})
export class PostsModule {}
