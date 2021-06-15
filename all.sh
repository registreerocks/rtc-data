#!/bin/sh -e
# Check, build, and test everything

echo "################################################################################"
echo "# make enclaves"
echo "################################################################################"
for enclave in 'rtc_data_enclave' 'rtc_auth_enclave' 'rtc_exec_enclave'; do
  ./_hack_timestamp.sh
  (cd "$enclave" && make)
done

# TODO: doc --document-private-items
for action in check build doc test; do

  for root in rtc_tenclave rtc_data_enclave rtc_auth_enclave rtc_exec_enclave .; do

    args=''
    case "$root $action" in

      # Skip enclave tests: not supported yet.
      'rtc_'*'_enclave test') continue ;;

      # Only the root project can build all targets, so far
      '. build') args='--all-targets' ;;


      # FIXME: Skip enclave docs for now: rustdoc doesn't support const_evaluatable_checked yet.
      # Issue: https://github.com/rust-lang/rust/issues/77647
      'rtc_'*'enclave doc') continue ;;

      # FIXME: Only the rtc_types docs build successfully right now.
      '. doc') args='--no-deps --package rtc_types' ;;

      # Skip documenting dependencies, by default
      *' doc') args='--no-deps' ;;

      # rtc_tenclave can test, but only with --no-default-features
      'rtc_tenclave test') args='--no-default-features' ;;

    esac

    # Show a big banner to make it easier to find and re-run failing commands.
    echo "################################################################################"
    echo "# (cd $root && cargo $action $args)"
    echo "################################################################################"
    ./_hack_timestamp.sh
    (cd "$root" && cargo "$action" $args)
  done

done

# Final timestamp reset, for good measure.
./_hack_timestamp.sh
