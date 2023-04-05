import { Injectable } from '@nestjs/common';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Post } from './entities/post.entity';
import { User } from 'src/users/entities/user.entity';

@Injectable()
export class PostsService {
  constructor(@InjectRepository(Post) private postsRepository: Repository<Post>) {}

  async create(user: User, createPostDto: CreatePostDto) {
    const post = new Post();
    post.body = createPostDto.body;
    post.title = createPostDto.title;
    post.user = user;

    await this.postsRepository.save(post)
  }

  findAll() {
    return `This action returns all posts`;
  }

  async findOne(id: number) {
    return await this.postsRepository.findOneBy({id})
  }

  update(id: number, updatePostDto: UpdatePostDto) {
    return `This action updates a #${id} post`;
  }

  remove(id: number) {
    return `This action removes a #${id} post`;
  }
}
