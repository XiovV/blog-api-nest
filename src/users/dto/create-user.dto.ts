import { ApiProperty } from "@nestjs/swagger"
import { IsEmail, MinLength } from "class-validator"

export class CreateUserDto {
    @ApiProperty()
    @IsEmail()
    email: string

    @ApiProperty({
        minimum: 5,
    })
    @MinLength(5)
    password: string

    @ApiProperty({
        minimum: 2
    })
    @MinLength(2)
    username: string
}