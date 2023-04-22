import { Controller, Get, Post, Body, Patch, Param, Delete, Version, UseGuards, ValidationPipe, Request, HttpVersionNotSupportedException, UnauthorizedException, NotFoundException } from '@nestjs/common';
import { PostsService } from './posts.service';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { JwtGuard } from 'src/auth/jwt.guard';
import { User } from 'src/users/entities/user.entity';
import { Post as PostEntity } from './entities/post.entity';
import { ApiBearerAuth, ApiCreatedResponse, ApiForbiddenResponse, ApiNotFoundResponse, ApiOkResponse, ApiOperation, ApiTags, ApiUnauthorizedResponse } from '@nestjs/swagger';
import { BasePost } from './entities/base-post.entity';
import { DefaultNotFoundError, DefaultUnauthorizedError, InsufficientPermissionsError, NotFoundError } from 'src/swagger/swagger.responses';
import { Casbin } from 'src/casbin/casbin';

@ApiTags('posts')
@Controller('posts')
export class PostsController {
  constructor(private readonly postsService: PostsService, private casbin: Casbin) { }

  @ApiOperation({ summary: "Creates a new post." })
  @ApiCreatedResponse({ description: "Post has been created successfully", type: BasePost })
  @ApiUnauthorizedResponse({ description: "The access token is invalid", type: DefaultUnauthorizedError })
  @ApiBearerAuth()
  @Version('1')
  @UseGuards(JwtGuard)
  @Post()
  create(@Body(new ValidationPipe()) createPostDto: CreatePostDto, @Request() req) {
    const user: User = req.user;

    return this.postsService.create(user, createPostDto);
  }

  @ApiOperation({ summary: "Gets a post by ID." })
  @ApiOkResponse({ type: BasePost })
  @ApiNotFoundResponse({ type: DefaultNotFoundError })
  @ApiUnauthorizedResponse({ description: "The access token is invalid", type: DefaultUnauthorizedError })
  @ApiBearerAuth()
  @Version('1')
  @UseGuards(JwtGuard)
  @Get(':id')
  async findOne(@Param('id') id: number) {
    const post = await this.postsService.findOne(id);
    if (!post) {
      throw new NotFoundException()
    }

    const basePost = new BasePost()
    basePost.id = post.id
    basePost.title = post.title
    basePost.body = post.body

    return basePost;
  }

  @ApiOperation({ summary: "Gets a list of user's posts." })
  @ApiOkResponse({ type: BasePost })
  @ApiNotFoundResponse({ type: DefaultNotFoundError })
  @ApiUnauthorizedResponse({ description: "The access token is invalid", type: DefaultUnauthorizedError })
  @ApiBearerAuth()
  @Version('1')
  @UseGuards(JwtGuard)
  @Get('user/:username')
  async getUsersPosts(@Param('username') username: string) {
    return await this.postsService.getUsersPosts(username)
  }

  @ApiOperation({ summary: "Update a post.", description: "Post updates are controlled with permissions. A normal user cannot update someone else's posts, but moderators and admins can." })
  @ApiForbiddenResponse({ description: "Insufficient permissions", type: InsufficientPermissionsError })
  @ApiUnauthorizedResponse({ description: "The access token is invalid", type: DefaultUnauthorizedError })
  @ApiBearerAuth()
  @Version('1')
  @UseGuards(JwtGuard)
  @Patch(':id')
  async update(@Param('id') id: number, @Body() updatePostDto: UpdatePostDto, @Request() req) {
    const user: User = req.user;
    return await this.postsService.update(user, id, updatePostDto);
  }

  @ApiOperation({ summary: "Delete a post.", description: "Post deletions are controlled with permissions. A normal user cannot delete someone else's posts, but moderators and admins can." })
  @ApiOkResponse({ description: "Post deleted successfully" })
  @ApiNotFoundResponse({ type: DefaultNotFoundError })
  @ApiForbiddenResponse({ description: "Insufficient permissions", type: InsufficientPermissionsError })
  @ApiUnauthorizedResponse({ description: "The access token is invalid", type: DefaultUnauthorizedError })
  @ApiBearerAuth()
  @Version('1')
  @UseGuards(JwtGuard)
  @Delete(':id')
  async remove(@Param('id') id: number, @Request() req) {
    const user: User = req.user;

    const post: PostEntity = await this.postsService.findOne(id);
    if (!post) {
      throw new NotFoundException()
    }

    const canDelete = await this.casbin.enforce(user.role.name, 'post', 'delete')
    if (post.user.id !== user.id && !canDelete) {
      throw new UnauthorizedException();
    }

    return await this.postsService.remove(user, id);
  }
}
