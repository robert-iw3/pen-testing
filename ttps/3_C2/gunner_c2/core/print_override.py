import builtins
import logging
from contextvars import ContextVar
from types import SimpleNamespace
from core.utils import echo

logger = logging.getLogger(__name__)


# stash the real print
_orig_print = builtins.print

"""# single, global context object
_ctx = SimpleNamespace(to_console=True, to_op=None, world=False)"""

to_console_var = ContextVar("to_console", default=True)
to_op_var      = ContextVar("to_op",      default=None)
world_var      = ContextVar("world",      default=False)


def set_output_context(to_console: bool=True, to_op: str=None, world_wide: bool=False):
    """Adjust where print() goes for the entire process."""
    logger.debug("set_output_context: to_console=%r, to_op=%r, world_wide=%r",to_console, to_op, world_wide)
    to_console_var.set(to_console)
    to_op_var.set(to_op)
    world_var.set(world_wide)

def _print(*args, sep=' ', end='\n', color=None, **kwargs):
    # build the string
    msg = sep.join(str(a) for a in args)
    # pull from our global context (no AttributeError possible)
    """console = _ctx.to_console
    op      = _ctx.to_op
    world = _ctx.world"""

    console = to_console_var.get()
    op      = to_op_var.get()
    world   = world_var.get()
    flush = kwargs.pop("flush", False)
    logger.debug("_print called: msg=%r, color=%r, to_console=%r, to_op=%r, world=%r, end=%r",msg, color, console, op, world, end)

    try:
        echo(msg,
            to_console=console,
            to_op=op,
            world_wide=world,
            color=color,
            _raw_printer=_orig_print,
            end=end)
        logger.debug("echo delivered successfully")

    except Exception as e:
        logger.exception("error in overridden print/echo: %s", e)

    if flush:
         _orig_print("", end="", flush=True)

# override built‑in print for every thread
builtins.print = _print