import { Length } from "class-validator"

export class CreatePostDto {
    userId: number

    @Length(1, 5000)
    body: string

    @Length(1, 200)
    title: string
}
