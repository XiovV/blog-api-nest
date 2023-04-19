import { ApiProperty } from "@nestjs/swagger";
import { Length } from "class-validator";

export class ConfirmMfaDto {
    @ApiProperty()
    @Length(52, 52)
    secret: string;

    @ApiProperty()
    @Length(6, 6)
    totp: string;
}