import { HttpException, HttpStatus, Inject, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';
import * as speakeasy from 'speakeasy'
import { ConfigService } from '@nestjs/config';
import { authConstants } from './constants';
import { CryptoService } from 'src/crypto/crypto.service';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { Logger, child } from 'winston'

@Injectable()
export class AuthService {
    private readonly logger: Logger
    constructor(private usersService: UsersService, private jwtService: JwtService, private config: ConfigService, private cryptoService: CryptoService, @Inject(WINSTON_MODULE_PROVIDER) private readonly winston: Logger) {
        this.logger = this.winston.child({context: AuthService.name})
    }

    async login(username: string, password: string, totp?: string): Promise<any> {
        const childLogger = this.logger.child({ username })
        childLogger.info('attempting to a log a user in')

        const user = await this.validateLoginCredentials(username, password);
        if (!totp && user.mfaSecret) {
            childLogger.warn('user login failed', { error: 'user has 2FA enabled a totp code was not provided' })
            throw new HttpException('this user has 2FA enabled, please provide a totp code', HttpStatus.FORBIDDEN);
        }

        if (!user.mfaSecret) {
            this.logger.info('user logged in successfully')
            return await this.generateTokenPair(user);
        }

        //TODO: consider wrapping this into a function
        childLogger.info('attemptign to verify totp code')
        const decryptedSecret = await this.cryptoService.decryptMfaSecret(user.mfaSecret)
        const isTOTPValid = this.verifyTOTPCode(totp, decryptedSecret);

        if (!isTOTPValid) {
            childLogger.warn('the provided totp code incorrect')
            throw new HttpException('totp code is incorrect', HttpStatus.UNAUTHORIZED)
        }

        childLogger.info('user logged in successfully')
        return await this.generateTokenPair(user);
    }

    async validateLoginCredentials(username: string, password: string): Promise<User> {
        const childLogger = this.logger.child({ username })
        childLogger.info('validating login credentials')

        const user = await this.usersService.findOneByUsername(username).catch(() => { throw new InternalServerErrorException() });
        if (!user) {
            childLogger.warn('failed to validate login credentials', { error: 'username or password is incorrect' })
            throw new HttpException('username or password is incorrect', HttpStatus.UNAUTHORIZED);
        }

        const isPasswordValid = await argon2.verify(user.password, password)
        if (!isPasswordValid) {
            childLogger.warn('failed to validate login credentials', { error: 'username or password is incorrect' })
            throw new HttpException('username or password is incorrect', HttpStatus.UNAUTHORIZED);
        }

        return user;
    }

    async generateTokenPair(user: User) {
        this.logger.info('generating token pair', { user: user.username })

        const accessTokenClaims = { sub: user.id, username: user.username }
        const refreshTokenClaims = { sub: user.id, type: "REFRESH" }

        return {
            accessToken: await this.jwtService.signAsync(accessTokenClaims, { secret: this.config.get('JWT_SECRET'), expiresIn: '15min' }),
            refreshToken: await this.jwtService.signAsync(refreshTokenClaims, { secret: this.config.get('JWT_SECRET'), expiresIn: '2y' })
        }
    }

    async validateRefreshToken(refreshToken: string, userId: number) {
        const payload = await this.jwtService.verifyAsync(refreshToken, { secret: this.config.get('JWT_SECRET') }).catch(() => { 
            throw new UnauthorizedException() 
        });

        if (payload.sub !== userId) {
            throw new UnauthorizedException();
        }
    }

    generateMfaSecret(): string {
        const secret = speakeasy.generateSecret();

        return secret.base32;
    }

    verifyTOTPCode(code: string, secret: string): boolean {
        return speakeasy.totp.verify({ secret: secret, encoding: 'base32', token: code })
    }

    generateRecoveryCodes(): string[] {
        let recoveryCodes: string[] = [];

        for (let i = 0; i < authConstants.numRecoveryCodes; i++) {
            let newRecoveryCode = Math.random().toString(16).substring(2, authConstants.recoveryCodeLength + 2);
            recoveryCodes.push(newRecoveryCode)
        }

        return recoveryCodes;
    }
}
