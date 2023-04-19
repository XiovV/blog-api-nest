import { ApiProperty } from "@nestjs/swagger";
import { IsEmail } from "class-validator";

export class PasswordResetEmailDto {
    @ApiProperty()
    @IsEmail()
    email: string
}