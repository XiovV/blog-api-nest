import { Injectable, UnauthorizedException } from '@nestjs/common';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Post } from './entities/post.entity';
import { User } from 'src/users/entities/user.entity';

@Injectable()
export class PostsService {
  constructor(@InjectRepository(Post) private postsRepository: Repository<Post>, @InjectRepository(User) private usersRepository: Repository<User>) {}

  async create(user: User, createPostDto: CreatePostDto) {
    const post = new Post();
    post.body = createPostDto.body;
    post.title = createPostDto.title;
    post.user = user;

    await this.postsRepository.save(post)
  }

  async findOne(id: number) {
    const post: Post[] =  await this.postsRepository.find({where: {id}, relations: {user: true}})
    return post[0];
  }

  async getUsersPosts(username: string) {
    const user: User = await this.usersRepository.findOneBy({username})

    return await this.postsRepository.createQueryBuilder('post')
    .where('post.userId = :userId', { userId: user.id })
    .getMany();
  }

  async remove(user: User, id: number) {
    await this.postsRepository.delete({id})
  }

  async update(user: User, id: number, updatePostDto: UpdatePostDto) {
    const result = await this.postsRepository.find({where: {id}, relations: {user: true}})
    const post: Post = result[0]

    if (user.id !== post.user.id) {
      throw new UnauthorizedException()
    }

    post.body = updatePostDto.body;
    post.title = updatePostDto.title;

    await this.postsRepository.save(post);
  }
}
