import { Length } from "class-validator";

export class ConfirmMfaDto {
    @Length(52, 52)
    secret: string;

    @Length(6, 6)
    totp: string;
}