# Target library
lib := libfs.a
objs		:= fs.o disk.o
CC      := gcc
AR 			:= ar rcs
CFLAGS  := -MMD #-Wall -Wextra -Werror
#CFLAGS  += -g

ifneq ($(V),1)
Q = @
endif

all: $(lib)

deps := $(patsubst %.o,%.d,$(objs))
-include $(deps)

$(lib): $(objs)
	@echo "AR $@"
	$(Q)$(AR) -o $@ $^

%.o: %.c
	@echo "CC $@"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@echo "clean"
	rm -f $(lib) $(objs) $(deps)
