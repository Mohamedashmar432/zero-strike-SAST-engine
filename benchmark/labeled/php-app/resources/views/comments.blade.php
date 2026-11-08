@extends('layouts.app')

@section('content')
<h1>Comments on {{ $note->title }}</h1>
@foreach ($comments as $comment)
    <div class="comment">
        <strong>{{ $comment->author }}</strong>
        <div class="body">{!! $comment->body !!}</div>
    </div>
@endforeach
<p>You searched for: <?= $_GET['q'] ?></p>
<p>Sorted by: <?= e($_GET['sort'] ?? 'date') ?></p>
@endsection
