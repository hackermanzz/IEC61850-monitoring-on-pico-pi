# Foundation checkpoint: only the shared runtime is linked.
# Explicit selection keeps local, uncommitted subsystem work out of this image.
TEMP_SRCS = ../app_program/app_main.c ../app_program/monitor_time.c ../app_program/monitor_memory.c
APP_CFLAGS ?= -Wall -Wextra -Werror -fstack-usage
TEMP_OBJS = $(TEMP_SRCS:.c=.o)
TEMP_DEPS = $(TEMP_SRCS:.c=.d)
OBJS += $(subst ../, ./mtkernel_3/, $(TEMP_OBJS))
C_DEPS += $(subst ../, ./mtkernel_3/, $(TEMP_DEPS))
mtkernel_3/app_program/%.o: ../app_program/%.c
	@mkdir -p $(dir $@)
	$(GCC) $(CFLAGS) $(APP_CFLAGS) -D$(TARGET) $(INCPATH) -MF"$(@:%.o=%.d)" -MT"$(@)" -c -o "$@" "$<"
