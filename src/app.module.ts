import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './users/entities/user.entity';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { CryptoModule } from './crypto/crypto.module';
import { BlacklistedToken } from './users/entities/token-blacklist.entity';
import { MailerModule } from './mailer/mailer.module';
import { PasswordResetToken } from './users/entities/password-reset-token.entity';
import { PostsModule } from './posts/posts.module';
import { Post } from './posts/entities/post.entity';
import { Role } from './users/entities/role.entity';

@Module({
  imports: [ConfigModule.forRoot({isGlobal: true}), TypeOrmModule.forRootAsync({
    imports: [ConfigModule],
    useFactory: (configService: ConfigService) => ({
      type: 'postgres',
      host: configService.get('DATABASE_HOST'),
      port: +configService.get('DATABASE_PORT'),
      username: configService.get('DATABASE_USERNAME'),
      password: configService.get('DATABASE_PASSWORD'),
      database: configService.get('DATABASE'),
      entities: [User, BlacklistedToken, PasswordResetToken, Post, Role],
      synchronize: true,
    }),
    inject: [ConfigService]

  }), UsersModule, AuthModule, CryptoModule, MailerModule, PostsModule],
})
export class AppModule {}
