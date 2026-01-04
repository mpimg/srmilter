#[deprecated = "use struct MailInfo log() method instead"]
#[macro_export]
macro_rules! log {
    ($mi: expr, $($args:tt)*) => {
        println!("{}: {}", $mi.get_id(), format_args!($($args)*));
    }
}

#[macro_export]
macro_rules! _result {
    ($mi: expr, $result_val: expr $(,)?) => {
        $mi.log(&format!("{} (by {} line {})", $result_val.uc(), file!(), line!()));
        return $result_val;
    };
    ($mi: expr, $result_val: expr, $($args:tt)* ) => {
        $mi.log(&format!("{} ({})", $result_val.uc(), format_args!($($args)*)));
        return $result_val;
    }
}

#[deprecated = "use struct MailInfo methods instead"]
#[macro_export]
macro_rules! accept {
    ($mi: expr, $($args:tt)*) => {
        _result!($mi, ClassifyResult::Accept, $($args)*)
    };
    ($mi: expr) => {
        _result!($mi, ClassifyResult::Accept)
    }
}

#[deprecated = "use struct MailInfo methods instead"]
#[macro_export]
macro_rules! quarantine {
    ($mi: expr, $($args:tt)*) => {
        _result!($mi, ClassifyResult::Quarantine, $($args)*)
    };
    ($mi: expr) => {
        _result!($mi, ClassifyResult::Quarantine)
    }
}

#[deprecated = "use struct MailInfo methods instead"]
#[macro_export]
macro_rules! reject {
    ($mi: expr, $($args:tt)*) => {
        _result!($mi, ClassifyResult::Reject, $($args)*)
    };
    ($mi: expr) => {
        _result!($mi, ClassifyResult::Reject)
    }
}
