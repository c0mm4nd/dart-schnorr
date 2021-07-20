class SchnorrException implements Exception {
  late String message;

  SchnorrException(this.message);

  @override
  String toString() {
    Object? message = this.message;
    return 'SchnorrException: $message';
  }

  @override
  int get hashCode => message.hashCode;

  @override
  bool operator ==(dynamic other) =>
      other is SchnorrException && message == other.message;
}
