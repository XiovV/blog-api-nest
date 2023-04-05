import { Length } from "class-validator"

export class CreatePostDto {
    @Length(1, 5000)
    body: string

    @Length(1, 200)
    title: string
}
