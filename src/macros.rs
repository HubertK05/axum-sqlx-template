#[allow(unused_macros)]
macro_rules! params_vec {
    ({$($out:expr),*}) => {
        vec![$($out),*]
    };
    ({$($out:expr),+} %$first:expr) => {
        params_vec!({$($out),*, $first.to_string()})
    };
    ({} %$first:expr) => {
        params_vec!({$first.to_string()})
    };
    ({$($out:expr),+} %$first:expr, $($sigil:tt $param:tt),*) => {
        params_vec!({$($out),*, $first.to_string()} $($sigil $param),*)
    };
    ({} %$first:expr, $($sigil:tt $param:tt),*) => {
        params_vec!({$first.to_string()} $($sigil $param),*)
    };
    ({$($out:expr),+} ?$first:expr) => {
        params_vec!({$($out),*, format!("{:?}", $first)})
    };
    ({} ?$first:expr) => {
        params_vec!({format!("{:?}", $first)})
    };
    ({$($out:expr),+} ?$first:expr, $($sigil:tt $param:tt),*) => {
        params_vec!({$($out),*, format!("{:?}", $first)} $($sigil $param),*)
    };
    ({} ?$first:expr, $($sigil:tt $param:tt),*) => {
        params_vec!({format!("{:?}", $first)} $($sigil $param),*)
    };
}

#[macro_export]
macro_rules! log_query_as {
    ($model:ty, $query:expr, $($sigil:tt $param:tt),*) => {{
        let params: Vec<String> = $crate::params_vec!({} $($sigil $param),*);

        let formatted_query = {
            let mut query = $query.to_string();
            for (i, param) in params.iter().enumerate() {
                let placeholder = format!("${}", i + 1);
                query = query.replace(&placeholder, param);
            }
            query
        };

        trace!("Executing query: {}", formatted_query);

        sqlx::query_as!($model, $query, $($param),*)
    }};
    
    ($model:ty, $query:expr) => {{
        let formatted_query = $query.to_string();

        trace!("Executing query: {}", formatted_query);

        sqlx::query_as!($model, $query)
    }};
}

#[macro_export]
macro_rules! log_query {
    ($query:expr, $($sigil:tt $param:tt),*) => {{
        let params: Vec<String> = $crate::params_vec!({} $($sigil $param),*);

        let formatted_query = {
            let mut query = $query.to_string();
            for (i, param) in params.iter().enumerate() {
                let placeholder = format!("${}", i + 1);
                query = query.replace(&placeholder, param);
            }
            query
        };

        trace!("Executing query: {}", formatted_query);

        sqlx::query!($query, $($param),*)
    }};
    
    ($query:expr) => {{
        let formatted_query = $query.to_string();

        trace!("Executing query: {}", formatted_query);

        sqlx::query!($query)
    }};
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;
    use rstest::rstest;

    #[allow(dead_code)]
    #[derive(Debug)]
    struct DisplayVsDebug;

    impl Display for DisplayVsDebug {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "This is the Display impl")
        }
    }

    #[rstest]
    #[case(params_vec!({}), vec![])]
    #[case(params_vec!({} %1), vec![1.to_string()])]
    #[case(params_vec!({} %1, ?2), vec![1.to_string(), 2.to_string()])]
    #[case(params_vec!({} %1, %2, %3, ?4, ?5, ?6), vec![1.to_string(), 2.to_string(), 3.to_string(), 4.to_string(), 5.to_string(), 6.to_string()])]
    #[case(params_vec!({} %DisplayVsDebug, ?DisplayVsDebug), vec![format!("{DisplayVsDebug}"), format!("{DisplayVsDebug:?}")])]
    fn params_vec_expands_correctly(#[case] tested: Vec<String>, #[case] expected: Vec<String>) {
        let expected: Vec<String> = expected.into_iter().map(|x| x.into()).collect();
        assert_eq!(tested, expected);
    }
}
