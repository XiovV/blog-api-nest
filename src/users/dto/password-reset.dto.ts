import { MinLength } from "class-validator";

export class PasswordResetDto {
    @MinLength(5)
    password: string
}