# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket; # skip_all => 'ngx_memc storage commands do not work with the ngx_eval module';

repeat_each(2);

plan tests => blocks() * (repeat_each() * 2);

#no_shuffle();
run_tests();

__DATA__

=== TEST 1: in server {}
--- config
    eval $var { echo hi; }
    location /t {
        echo $var;
    }
--- request
    GET /t
--- must_die
--- error_log eval
qr/\[emerg\] .*? "eval" directive is not allowed here/



=== TEST 2: in http {}
--- http_config
    eval $var { echo hi; }
--- config
    location = /t {
        echo $var;
    }
--- request
    GET /t
--- must_die
--- error_log eval
qr/\[emerg\] .*? "eval" directive is not allowed here/

