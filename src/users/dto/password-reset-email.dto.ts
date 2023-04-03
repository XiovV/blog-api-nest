import { IsEmail } from "class-validator";

export class PasswordResetEmailDto {
    @IsEmail()
    email: string
}