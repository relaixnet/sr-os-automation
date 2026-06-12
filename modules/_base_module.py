from pysros.management import Connection


class ModuleException(Exception):
    pass


# Abstract base class
class BaseModule:
    def __init__(self) -> None:
        self.config = dict()
        self.secrets_config = dict()

    def raise_exception(self, message: str) -> None:
        """
        Helper method to raise a ModuleException with proper format.

        :raises ModuleException:
        """
        class_name = self.__class__.__name__
        raise ModuleException(f"[{class_name}]: {message}")

    def validate_config(self) -> None:
        """
        Validates that the given module configuration is valid. Raises ModuleException if not.

        :raises ModuleException: if invalid
        """
        pass

    def run(self, connection: Connection) -> None:
        """
        Main entrypoint of the module. Gets a connection instance as a parameter.
        This method should use the connection instance to modify a config group in the candidate config.

        Note: Always use `commit=False` in set()-Calls of the connection instance.

        :raises ModuleException: on errors
        """
        pass

    def post_run(self) -> None:
        """
        Method that gets called after diff output and commit. Useful to print summaries of the module run.
        """
        pass
