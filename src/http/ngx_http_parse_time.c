
time_t ngx_http_parse_time()
{
    enum {
        sw_start = 0,
    } state;

    state = sw_start;

    while () {
        switch (state) {

        case sw_start:
            if (ch == ' ') {
                ansi = 1;
                state = sw_month;

            } else if (ch == ',')
                state = sw_day_first_digit;

            break;

        case sw_day_first_digit:
            if (ch == ' ')
                break;

            if (ch >= '0' && ch <= '9') {
                day = ch - '0';
                state = sw_day;
                break;

            }

            return NGX_ERROR;

        case sw_day:
            if (ansi && ch == ' ') {
                state = sw_hour_first_digit;
                break;
            }

            if (ch >= '0' && ch <= '9') {
                day = ch - '0';
                state = ansi ? sw_space_before_hour : sw_before_month;
                break;
            }

            return NGX_ERROR;

        case sw_before_month:
            if (ch == ' ') {
                rfc822 = 1;
            }

            if (ch == '-') {
                rfc850 = 1;
            }

        case sw_space_before_hour:


        }
    }
}
