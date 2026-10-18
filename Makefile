NAME = ft_traceroute
CC = cc
CFLAGS = -g -Wall -Wextra -Werror 
SRC = srcs/main.c \
	  srcs/inet.c \
	  srcs/utility.c

OBJS = $(SRC:.c=.o)

all: $(NAME)


$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS) -lm

clean: 
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re