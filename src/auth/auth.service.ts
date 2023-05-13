import { HttpException, HttpStatus, Injectable, InternalServerErrorException, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';
import * as speakeasy from 'speakeasy'
import { ConfigService } from '@nestjs/config';
import { authConstants } from './constants';
import { CryptoService } from 'src/crypto/crypto.service';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name)
    constructor(private usersService: UsersService, private jwtService: JwtService, private config: ConfigService, private cryptoService: CryptoService) { }

    async login(username: string, password: string, totp?: string): Promise<any> {
        this.logger.log({ username }, 'validating login credentials')
        const user = await this.validateLoginCredentials(username, password);

        if (!totp && user.mfaSecret) {
            this.logger.log({ username, error: 'user has 2FA enabled but a totp wasn not provided' }, 'user login failed')
            throw new HttpException('this user has 2FA enabled, please provide a totp code', HttpStatus.FORBIDDEN);
        }

        if (!user.mfaSecret) {
            this.logger.log({username}, 'user logged in successfully')
            return await this.generateTokenPair(user);
        }

        const decryptedSecret = await this.cryptoService.decryptMfaSecret(user.mfaSecret)
        const isTOTPValid = this.verifyTOTPCode(totp, decryptedSecret);

        if (!isTOTPValid) {
            this.logger.error({username}, 'the provided totp code is incorrect')
            throw new HttpException('totp code is incorrect', HttpStatus.UNAUTHORIZED)
        }

        this.logger.log({username}, 'user logged in successfully')
        return await this.generateTokenPair(user);
    }

    async validateLoginCredentials(username: string, password: string): Promise<User> {
        const user = await this.usersService.findOneByUsername(username).catch(() => { throw new InternalServerErrorException() });
        if (!user) {
            this.logger.error({username, error: 'username or password is incorrect'}, 'failed to validate login credentials')
            throw new HttpException('username or password is incorrect', HttpStatus.UNAUTHORIZED);
        }

        const isPasswordValid = await argon2.verify(user.password, password)
        if (!isPasswordValid) {
            this.logger.error({username, error: 'username or password is incorrect'}, 'failed to validate login credentials')
            throw new HttpException('username or password is incorrect', HttpStatus.UNAUTHORIZED);
        }

        return user;
    }

    async generateTokenPair(user: User) {
        const accessTokenClaims = { sub: user.id, username: user.username }
        const refreshTokenClaims = { sub: user.id, type: "REFRESH" }

        return {
            accessToken: await this.jwtService.signAsync(accessTokenClaims, { secret: this.config.get('JWT_SECRET'), expiresIn: '15min' }),
            refreshToken: await this.jwtService.signAsync(refreshTokenClaims, { secret: this.config.get('JWT_SECRET'), expiresIn: '2y' })
        }
    }

    async validateRefreshToken(refreshToken: string, userId: number) {
        const payload = await this.jwtService.verifyAsync(refreshToken, { secret: this.config.get('JWT_SECRET') }).catch(() => { throw new UnauthorizedException() });

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
