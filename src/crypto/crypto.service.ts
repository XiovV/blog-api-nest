import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as aes256 from 'aes256';

@Injectable()
export class CryptoService {
    password: string;

    constructor(config: ConfigService) {
        this.password = config.get('AES_KEY');
    }

    encryptMfaSecret(secret: string) {
        const encryptedSecret = aes256.encrypt(this.password, Buffer.from(secret))

        return encryptedSecret;
    }

    decryptMfaSecret(secret: Buffer): Promise<string> {
        const decryptedBuffer = aes256.decrypt(this.password, secret)

        return decryptedBuffer.toString();
    }
}
