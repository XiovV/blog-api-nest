import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
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
import { WinstonModule } from 'nest-winston';
import * as winston from 'winston'
import { LoggerMiddleware } from './logger/logger.middleware';

@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true }),
  TypeOrmModule.forRootAsync({
    imports: [ConfigModule],
    inject: [ConfigService],
    useFactory: (config: ConfigService) => ({
      type: 'postgres',
      host: config.get('DATABASE_HOST'),
      port: +config.get('DATABASE_PORT'),
      username: config.get('DATABASE_USERNAME'),
      password: config.get('DATABASE_PASSWORD'),
      database: config.get('DATABASE'),
      entities: [User, BlacklistedToken, PasswordResetToken, Post, Role],
      synchronize: true,
    }),
  }),
  WinstonModule.forRootAsync({
    imports: [ConfigModule],
    inject: [ConfigService],
    useFactory: (config: ConfigService) => ({
      level: config.get('LOG_LEVEL') || 'info',
      transports: [
        new winston.transports.Console({ format: config.get('NODE_ENV') === 'production' ? winston.format.json() : winston.format.simple() })
      ],
    }),
  }),
    UsersModule, AuthModule, CryptoModule, MailerModule, PostsModule],
  providers: [],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleware).forRoutes('*');
  }
}
