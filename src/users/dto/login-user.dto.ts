import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger"
import { Length, MinLength } from "class-validator"

export class LoginUserDto {
    @ApiProperty({
        minimum: 5
    })
    @MinLength(5)
    password: string

    @ApiProperty({
        minimum: 2
    })
    @MinLength(2)
    username: string

    @ApiPropertyOptional()
    totp?: string
}
