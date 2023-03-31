import { HttpException, HttpStatus, Injectable, InternalServerErrorException } from '@nestjs/common';
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
    constructor(private usersService: UsersService, private jwtService: JwtService, private config: ConfigService, private cryptoService: CryptoService) { }

    async login(username: string, password: string, totp?: string): Promise<any> {
        const user = await this.usersService.findOneByUsername(username).catch(() => { throw new InternalServerErrorException });

        if (!user) {
            throw new HttpException('username or password is incorrect', HttpStatus.UNAUTHORIZED);
        }

        const isPasswordValid = await argon2.verify(user.password, password)

        if (!isPasswordValid) {
            throw new HttpException('username or password is incorrect', HttpStatus.UNAUTHORIZED);
        }

        if (!totp && user.mfaSecret) {
            throw new HttpException('this user has 2FA enabled, please provide a totp code', HttpStatus.UNAUTHORIZED);
        }

        if (totp && user.mfaSecret) {
            const decryptedSecret = await this.cryptoService.decryptMfaSecret(user.mfaSecret)
            const isTOTPValid = this.verifyTOTPCode(totp, decryptedSecret);

            if (!isTOTPValid) {
                throw new HttpException('totp code is incorrect', HttpStatus.UNAUTHORIZED)
            }
        }


        return await this.generateTokenPair(user);
    }

    async generateTokenPair(user: User) {
        const accessTokenClaims = { sub: user.id, username: user.username }
        const refreshTokenClaims = { sub: user.id, type: "REFRESH" }

        return {
            access_token: this.jwtService.sign(accessTokenClaims, { secret: this.config.get('JWT_SECRET'), expiresIn: '15min' }),
            refresh_token: this.jwtService.sign(refreshTokenClaims, { secret: this.config.get('JWT_SECRET'), expiresIn: '2y' })
        }
    }

    generateMfaSecret(): string {
        const secret = speakeasy.generateSecret();

        return secret.base32;
    }

    verifyTOTPCode(code: string, secret: string): boolean {
        return speakeasy.totp.verify({secret: secret, encoding: 'base32', token: code})
    }

    generateRecoveryCodes(): string[] {
        let recoveryCodes: string[] = [];

        for(let i = 0; i < authConstants.numRecoveryCodes; i++) {
            let newRecoveryCode = Math.random().toString(16).substring(2, authConstants.recoveryCodeLength);
            recoveryCodes.push(newRecoveryCode)
        }

        return recoveryCodes;
    }
}
