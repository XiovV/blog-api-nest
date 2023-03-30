import { Length, MinLength } from "class-validator"

export class LoginUserMfaDto {
    @MinLength(5)
    password: string

    @MinLength(2)
    username: string

    @Length(6, 6)
    totp: string
}