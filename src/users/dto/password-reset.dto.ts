import { ApiProperty } from "@nestjs/swagger";
import { MinLength } from "class-validator";

export class PasswordResetDto {
    @ApiProperty({minLength: 5})
    @MinLength(5)
    password: string
}