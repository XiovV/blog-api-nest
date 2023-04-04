import { Column, Entity, JoinColumn, ManyToOne, OneToOne, PrimaryGeneratedColumn } from "typeorm";
import { User } from "./user.entity";

@Entity()
export class PasswordResetToken {
    @PrimaryGeneratedColumn()
    id: number

    @Column({unique: true})
    token: string

    @Column({type: 'bigint'})
    expiry: number

    @ManyToOne(() => User, user => user.passwordResetTokens)
    user: User
}