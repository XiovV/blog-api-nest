import { Length, MinLength } from "class-validator"

export class LoginUserDto {
    @MinLength(5)
    password: string

    @MinLength(2)
    username: string

    totp?: string
}
