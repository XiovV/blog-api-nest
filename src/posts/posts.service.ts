import { HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Post } from './entities/post.entity';
import { User } from 'src/users/entities/user.entity';
import { BasePost } from './entities/base-post.entity';
import { InsufficientPermissionsException } from 'src/errors/insufficient-permissions.exception';
import { IPaginationOptions, paginate } from 'nestjs-typeorm-paginate';

@Injectable()
export class PostsService {
  constructor(@InjectRepository(Post) private postsRepository: Repository<Post>, @InjectRepository(User) private usersRepository: Repository<User>) {}

  async create(user: User, createPostDto: CreatePostDto): Promise<BasePost> {
    const post = new Post();
    post.body = createPostDto.body;
    post.title = createPostDto.title;
    post.user = user;

    const createdPost =  await this.postsRepository.save(post)

    const basePost = new BasePost()
    basePost.id = createdPost.id
    basePost.title = createdPost.title
    basePost.body = createdPost.body

    return basePost
  }

  async findOne(id: number) {
    const post: Post[] =  await this.postsRepository.find({where: {id}, relations: {user: true}})
    return post[0];
  }

  async getUsersPosts(username: string, options: IPaginationOptions) {
    const user: User = await this.usersRepository.findOneBy({username})

    const queryBuilder = this.postsRepository.createQueryBuilder('post');
    queryBuilder.where('post.userId = :userId', { userId: user.id })
    .orderBy('post.id', 'ASC')
    .getMany();
    
    return paginate<Post>(queryBuilder, options)
  }

  async remove(id: number) {
    await this.postsRepository.delete({id})
  }

  async update(user: User, id: number, updatePostDto: UpdatePostDto) {
    const result = await this.postsRepository.find({where: {id}, relations: {user: true}})
    const post: Post = result[0]

    if (user.id !== post.user.id) {
      throw new InsufficientPermissionsException() 
    }

    post.body = updatePostDto.body;
    post.title = updatePostDto.title;

    await this.postsRepository.save(post);
  }
}
