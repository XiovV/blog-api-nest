import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
    mailer: nodemailer.Transporter;

    constructor(config: ConfigService) {
        this.mailer = nodemailer.createTransport({
            host: config.get('SMTP_HOST'),
            port: config.get('SMTP_PORT'),
            auth: {
                user: config.get('SMTP_USERNAME'),
                pass: config.get('SMTP_PASSWORD'),
            }
        }) 
    }

    async sendPasswordResetMail(receiverEmail: string, username: string, token: string) {
        await this.mailer.sendMail({
            from: 'no-reply@blogapi.com',
            to: receiverEmail,
            subject: 'Password Reset Instructions For BlogAPI Account',
            text: `Hello ${username}! Here is your password reset token: ${token}`
        })
    }
}

