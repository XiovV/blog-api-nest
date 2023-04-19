import { ApiProperty } from "@nestjs/swagger"
import { Column, PrimaryGeneratedColumn } from "typeorm"

export class BasePost {
    @ApiProperty()
    @PrimaryGeneratedColumn()
    id: number

    @ApiProperty()
    @Column()
    title: string

    @ApiProperty()
    @Column()
    body: string
}