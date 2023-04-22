import { ApiProperty } from "@nestjs/swagger"
import { Length } from "class-validator"

export class CreatePostDto {
    @ApiProperty({minimum: 1, maximum: 5000})
    @Length(1, 5000)
    body: string

    @ApiProperty({minimum: 1, maximum: 200})
    @Length(1, 200)
    title: string
}
