import { IsEmail, MinLength } from "class-validator"
import { User } from "../entities/user.entity"

export class CreateUserDto {
    @IsEmail()
    email: string

    @MinLength(5)
    password: string

    @MinLength(2)
    username: string
}

