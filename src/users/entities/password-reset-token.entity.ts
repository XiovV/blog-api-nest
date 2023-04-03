import { Column, Entity, JoinColumn, ManyToOne, OneToOne, PrimaryGeneratedColumn } from "typeorm";
import { User } from "./user.entity";

@Entity()
export class PasswordResetToken {
    @PrimaryGeneratedColumn()
    id: number

    @Column({unique: true})
    token: string

    @Column()
    expiry: number

    @OneToOne(() => User)
    @JoinColumn()
    user: User
}