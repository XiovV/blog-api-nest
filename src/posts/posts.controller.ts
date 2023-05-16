import { Controller, Get, Post, Body, Patch, Param, Delete, Version, UseGuards, ValidationPipe, Request, HttpVersionNotSupportedException, UnauthorizedException, NotFoundException, HttpException, HttpStatus, Query, DefaultValuePipe, ParseIntPipe, Inject } from '@nestjs/common';
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
import { RBACObject } from 'src/casbin/enum/object.enum';
import { RBACAction } from 'src/casbin/enum/action.enum';
import { InsufficientPermissionsException } from 'src/errors/insufficient-permissions.exception';
import { Logger } from 'winston';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';

@ApiTags('posts')
@Controller('posts')
export class PostsController {
  private readonly logger: Logger
  constructor(private readonly postsService: PostsService, private casbin: Casbin, @Inject(WINSTON_MODULE_PROVIDER) private readonly winston: Logger) {
    this.logger = this.winston.child({ context: PostsController.name })
  }

  @ApiOperation({ summary: "Creates a new post." })
  @ApiCreatedResponse({ description: "Post has been created successfully", type: BasePost })
  @ApiUnauthorizedResponse({ description: "The access token is invalid", type: DefaultUnauthorizedError })
  @ApiBearerAuth()
  @Version('1')
  @UseGuards(JwtGuard)
  @Post()
  create(@Body(new ValidationPipe()) createPostDto: CreatePostDto, @Request() req) {
    const user: User = req.user;
    this.logger.info('attempting to create a new post', { username: user.username })

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
  async findOne(@Param('id') id: number, @Request() req) {
    const user: User = req.user
    const childLogger = this.logger.child({ username: user.username, postId: id })

    childLogger.info('fetching a post by id')
    const post = await this.postsService.findOne(id);
    if (!post) {
      this.logger.warn('could not fetch post by post id', { error: 'post not found' })
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
  async getUsersPosts(@Param('username') username: string, @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number = 1, @Query('limit', new DefaultValuePipe(10), ParseIntPipe) limit: number = 10, @Request() req) {
    const user: User = req.user

    limit = limit > 100 ? 100 : limit

    this.logger.log('fetching post by username', { username: user.username, postUsername: username })
    return await this.postsService.getUsersPosts(username, { page, limit })
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

    this.logger.info('updating a post by id', { username: user.username, postToUpdateId: id })
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
    const childLogger = this.logger.child({ username: user.username, postToDeleteId: id })

    childLogger.info('attempting to delete a post by id')
    const post: PostEntity = await this.postsService.findOne(id);
    if (!post) {
      childLogger.warn('failed to delete a post by id', { error: 'post not found' })
      throw new NotFoundException()
    }

    childLogger.info('checking permissions')
    const canDelete = await this.casbin.enforce(user.role.name, RBACObject.Post, RBACAction.Delete)
    if (post.user.id !== user.id && !canDelete) {
      childLogger.warn('failed to delete a post by id', { error: 'user has insufficient permissions' })
      throw new InsufficientPermissionsException()
    }

    return await this.postsService.remove(id);
  }
}
