import { User } from "src/users/entities/user.entity";
import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { BasePost } from "./base-post.entity";

@Entity()
export class Post extends BasePost {
    @ManyToOne(() => User, user => user.posts)
    user: User
}